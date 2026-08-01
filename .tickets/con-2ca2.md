---
id: con-2ca2
status: open
deps: []
links: [con-be15]
created: 2026-07-31T19:37:56Z
type: bug
priority: 2
tags: [preproc, diagnostics, transforms, testing]
---

# _safe silently swallows BinderException, turning transform bugs into no-ops

_safe() (transforms.py:91, over the shared safe_execute) exists so a transform whose SOURCE TABLE is missing logs and skips instead of failing the run -- legitimate, since privilege level determines which tables exist. But it treats a genuine SQL coding error the same way: a BinderException from a column TYPE mismatch is swallowed and the transform silently becomes a no-op.\nThis is not hypothetical -- it shipped a broken fix during con-be15. A new gate used list_filter() on remoteregistry_computers.sccm_site_system_roles, which dlt lands as JSON rather than VARCHAR[]. list_filter cannot bind on JSON, so the statement raised BinderException, _safe swallowed it, and the gate did nothing in production while its unit tests (whose fixture wrongly declared VARCHAR[]) all passed. Nothing in the collect_full log even named the transform -- grepping the label returned zero hits -- so there was no trail to follow.\nWhy it matters beyond that one bug: every transform in this module is wrapped in _safe, so ANY type-mismatch typo anywhere in preprocess degrades to missing graph data with a green test suite and a silent log. The failure mode is invisible by construction.\nFIX DIRECTION: distinguish 'source table/column absent' (expected, keep skipping and logging as today) from 'statement failed to bind or execute for any other reason' (a bug -- log at ERROR naming the transform and the exception, and consider re-raising outside the expected-miss set). At minimum the label must appear in the log so the skip is greppable.

## Acceptance Criteria

A transform that fails for a reason other than a missing source is reported at ERROR naming the transform and the underlying exception; a missing source still skips quietly as today; a regression test covers a type-mismatch statement being reported rather than silently skipped.

## Notes

**2026-07-31T21:45:41Z**

INVESTIGATED + PART (A) DONE (2026-07-31). A parallel investigation and an independent adversarial verifier both confirmed the diagnosis, and the verifier found the real proximate cause was NOT what I assumed.
THE ACTUAL REASON THERE WAS 'NO TRAIL AT ALL': the per-run file handlers are torn down before preprocess runs. main.py's collect-phase finally removed both _ordered and _diag from the root logger, and the --run-all chain (preprocess + convert) executed AFTER that. So preproc failures reached NO on-disk log -- not collect_full, not collect_issues -- which is why grepping for a skipped transform's own label returned zero hits. The swallowing and the invisibility were two separate defects; only the second explains the missing trail.
FIXED HERE (A): the --run-all chain now runs inside its own try/finally and _diag stays attached across preprocess/convert, so transform failures land in collect_issues_*.log. _ordered is still detached with the collect phase -- its host/resource bucketing has no meaning in preproc. The finally is required rather than a trailing call because the integration suite exits via typer.Exit. Verified: ruff/mypy clean, CLI loads, full suite green.
STILL OPEN, LANDS IN openhound-collector-common (separate repo, cannot be fixed from here):
 (B1) duckdb_missing_table_name's regex matches 'with name X' generally, so 'Scalar Function with name X does not exist' and 'Schema with name X' masquerade as a missing SOURCE TABLE. Tighten to 'Table with name'.
 (B2) safe_execute should gate its quiet CatalogException arm on that match succeeding -- a catalog error that is NOT a missing table should fall through to the loud path.
 (B3) safe_execute should stop swallowing non-missing-source failures outright: either raise, or return a failure signal plus a tally the caller can act on. Confirmed by the investigation: BinderException is NOT a subclass of CatalogException, so the two are already distinguishable -- the code simply catches too broadly.
 (C) Once (B) lands, this repo's _safe should surface the tally and preproc should exit non-zero when any transform failed. Today a run with preproc BinderExceptions still exits 0.
 (D) Regression guard, this repo: type integration fixtures from the REAL dlt type. The con-be15 gate passed its tests while doing nothing in production because its fixture declared VARCHAR[] where dlt lands JSON. Consider a test asserting list_filter() is only ever applied to node_* columns or _arr(...) expressions, never a raw dlt column.
NOTE the verifier also caught that one corroborating artifact in the original writeup was misidentified -- a file in logs/ attributed to a preproc run is actually a pytest session log -- so the '110 preproc ERRORs' figure quoted there is unverified. The causal diagnosis stands on the code reading alone.

**2026-07-31T22:43:34Z**

PARTS B1 + B2 FIXED in openhound-collector-common (@_Mayyhem authorised the sibling repo 2026-07-31). dlt/duckdb_safe.py:
 (B1) duckdb_missing_table_name's regex is now anchored on 'Table with name'. DuckDB uses the same '<thing> with name <x> does not exist!' shape for scalar functions, schemas and sequences, so the unanchored match reported a misspelled FUNCTION as a missing source table.
 (B2) safe_execute now takes the loud path for any CatalogException that is NOT a missing source table. Only 'this table has not been produced yet' is an expected absence; a bad function or schema is a coding error.
Five tests written first; three failed, including the decisive one showing a misspelled list_filtr reported as "skipped (missing source)". Shared-library suite 117 passed, ruff and mypy clean.
CORRECTION to my earlier note on this ticket: B3 as filed ('safe_execute swallows BinderException silently') was WRONG about the silence. A BinderException already hits safe_execute's generic duckdb.Error arm and IS logged at ERROR naming the transform -- 'transform %r failed: %s'. The reason my grep found no trace was entirely part (A): main.py tore the file handlers down before preprocess ran, so that ERROR went to no on-disk log. Fixing (A) restored the trail; the taxonomy was never the silent part.
WHAT REMAINS (B3/C) IS A POLICY DECISION, NOT A BUG, so I have not done it: should a transform failure make preprocess exit non-zero? Today a run with N failed transforms logs N ERRORs and exits 0, so CI goes green on an incomplete graph. Implementing it means either raising from safe_execute (changes behaviour for EVERY consumer of the shared library, not just this collector) or adding a failure tally the caller reads. Needs @_Mayyhem's call on whether an incomplete graph should fail a run.
ALSO NOT YET EFFECTIVE IN THE COLLECTOR: ConfigManBearPig resolves openhound-collector-common 0.1.1 from PyPI, so B1/B2 reach it only after a new library release and a floor bump. (D) -- typing fixtures from the real dlt type -- was already applied in this repo during con-be15.
