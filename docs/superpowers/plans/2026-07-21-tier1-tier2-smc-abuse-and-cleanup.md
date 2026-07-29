# Tier 1 + Tier 2: Recursive SMC Holder Expansion, `--sms` Cleanup, and Lint Close-out — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recursively expand group holders of GenericAll on the System Management container so their member computers get scanned, remove the dead `--sms` flag, and clear the tree of lint errors so the code-quality ticket can close.

**Architecture:** This SCCM extension builds edges as SQL in `transforms.py` and collects via `collectors/*.py` yielding dicts into schema-less raw DLT tables. This plan touches only two files of substance — `collectors/ldap.py` (holder-loop recursion + delete unused parser locals) and `main.py`/`source.py` (flag removal + unused import). **No new edges, no graph-schema changes.**

**Tech Stack:** Python 3.14, DLT, DuckDB, ldap3, pytest. Package root: `sccm/sccm/src/openhound_sccm/`. Tests: `sccm/tests/`.

## Tickets covered
- **ope-b1e8** (Tier 1) — dead `--sms`/`--sms-provider` flag. Decision: **remove** it; document `-c/--computers`.
- **ope-e191** (Tier 2) — recursively expand group members of GenericAll holders on the System Management container (target discovery).
- **ope-1f0f** (Tier 1) — code-quality pass; the only failing acceptance criterion is a clean linter (4 F841 in `ldap.py`, 1 F401 in `main.py`).

## DEFERRED — left as an open ticket for later (per Meatbag, 2026-07-21)
- **Ope-liu7** (System Management Container Abuse → SCCM site-takeover **edges**) is **NOT** in this plan. Deferring it means we do **not**: generalize `_parse_sd_generic_all` to all five control rights, restructure the collector to per-ACE ACL rows, add the `SCCM_ControlSystemManagement` edge kind / `edge_help.py` block / `transforms.py` builder / edge properties. `Ope-liu7` stays `open`. See the "Deferred scope" section at the end for the exact work that remains, so it can be picked up cleanly.

## Global Constraints (apply to EVERY task)
- **NO COMMITS.** Per CLAUDE.md, do not `git add`/`git commit`. Each task ends at a **green checkpoint** (targeted tests pass); Meatbag commits.
- **Targeted tests only.** Run specific files with the extension venv: from `sccm/sccm/`, `.venv/Scripts/python -m pytest ../tests/<file>.py -q` (NOT the whole suite).
- **Branch logging — precise definition (replaces the vague term "non-happy branch"):** a *reportable branch* is any conditional path that does something other than continue the normal successful flow — specifically one that **(a)** skips or drops a record, **(b)** returns or `continue`s early, **(c)** falls through without producing output, or **(d)** handles a degraded / unexpected / error condition. Every reportable branch must emit a log with enough context to diagnose it, at: `debug` for optional/missing fields, `verbose` for noisy per-entry paths, `warning` for unexpected/degraded conditions, `error` for failures. **Explicitly exempt (no log required):** pure entry-guard clauses (e.g. `if not ctx.method_enabled("LDAP"): return`) and tight inner loops where per-iteration logging would flood output.
- **Preserve collector step ordering** to match ConfigManBearPig.ps1; do not reorder per-table emits.
- **dlt schema gotcha:** dlt snake_cases camelCase keys and drops all-NULL/absent columns; keep yielded keys consistent `snake_case` with non-null values.

## File Structure
| File | Change |
|---|---|
| `src/openhound_sccm/main.py` | Remove `--sms` option + `sms_provider` env map (`:148`, `:215-216`, `:967`); remove unused `ProxyConfig` import (`:611`). |
| `src/openhound_sccm/source.py` | Remove the unused `sms_provider` param (`:220`). |
| `src/openhound_sccm/collectors/ldap.py` | Add recursive group expansion to `ldap_system_management_dacl` (`:572-611`); delete the 4 unused locals in `_parse_sd_generic_all` (`:634`,`:635`,`:642`,`:660`). |
| `README.md` | Remove the `--sms` row; document `-c` for host scoping. |
| `tests/` | `test_ldap_smc_recursion.py` (new), `test_cli_argument_warnings.py` (flag removal). |

---

### Task 1: Remove the dead `--sms` flag (ope-b1e8)

**Files:**
- Modify: `src/openhound_sccm/main.py:148`, `:215-216`, `:967`
- Modify: `src/openhound_sccm/source.py:220`
- Modify: `README.md` (Command Line Options)
- Test: `tests/test_cli_argument_warnings.py`

**Interfaces:**
- Produces: `collect_sccm` no longer accepts `--sms`/`--sms-provider`; `source()` no longer takes `sms_provider`.

- [ ] **Step 1: Write the failing test** in `tests/test_cli_argument_warnings.py` (which already imports `openhound_sccm.main as sccm_main`). The Typer command `collect_sccm` is a plain module-level function (`@_collect_typer.command` returns the function unchanged), so introspect its signature — no `CliRunner` needed:

```python
import inspect

def test_sms_option_removed():
    from openhound_sccm import main as sccm_main
    from openhound_sccm import source as sccm_source
    assert "sms_provider" not in inspect.signature(sccm_main.collect_sccm).parameters
    assert "sms_provider" not in inspect.signature(sccm_source.source).parameters
```
(If `dlt.source` wrapping hides `source`'s signature, drop that second assert; the `collect_sccm` assertion is the behavioral guarantee.)

- [ ] **Step 2: Run it, expect FAIL** (param still present): `.venv/Scripts/python -m pytest ../tests/test_cli_argument_warnings.py::test_sms_option_removed -q`

- [ ] **Step 3: Remove the option and its plumbing.**
  - `main.py:967` — delete the `sms_provider: Optional[str] = typer.Option(None, "--sms", "--sms-provider", ...)` parameter and every use of `sms_provider` in that function body (it is only forwarded).
  - `main.py:148` — delete the `"sms_provider": "SOURCES__SCCM__SMS_PROVIDER",` env-map entry.
  - `main.py:215-216` — delete the `"--sms"`, `"--sms-provider"` entries from the flag list there.
  - `source.py:220` — delete the `sms_provider: str | None = dlt.config.value,` parameter.

- [ ] **Step 4: Run test, expect PASS.**

- [ ] **Step 5: Update docs.** In `README.md` Command Line Options, remove the `--sms/--sms-provider` row and add: "Use `-c/--computers <host>` to scope a run to specific hosts (e.g. an SMS Provider)."

- [ ] **Step 6: Green checkpoint (no commit).** `.venv/Scripts/python -m pytest ../tests/test_cli_argument_warnings.py ../tests/test_extension_methods.py -q` — expect PASS. Report; do not commit.

---

### Task 2: Recursive group expansion for GenericAll holders (ope-e191)

**Files:**
- Modify: `src/openhound_sccm/collectors/ldap.py:572-611` (`ldap_system_management_dacl` holder loop)
- Test: `tests/test_ldap_smc_recursion.py` (new)

**Interfaces (verified against live code):**
- `ctx.resolve_principal(identifier)` (`context.py:170`) already resolves a **distinguished name directly** via BASE scope when the identifier contains `"="` (`context.py:184-190`), returning the member's `ad_obj` dict with `object_sid`, `object_class`, `dns_host_name`, `distinguished_name`. So member DNs resolve with **no new method**.
- The resolved group `ad_obj` does **not** include its `member` list (neither `_ldap_resolve` nor `_ldap_resolve_dn` request that attribute). Fetch members with one BASE-scope search on the group DN requesting `member`, mirroring `_ldap_resolve_dn` (`context.py:227-236`): `ctx.ad.paged_search("(objectClass=*)", ["member"], base=group_dn, scope=BASE)`. Add `from ldap3 import BASE` to `ldap.py` (it is not yet imported there).
- `ctx.register_target(identifier=<dns_host_name>, source="LDAP-GenericAllSystemManagement", ad_object=<obj>)` registers a computer member (same call the direct-computer branch already uses).
- Produces: no table/schema change — the collector still yields the same `ad_obj` rows; recursion only adds more `register_target` calls (computer members) and info logs for user members.

**Design:** This is target discovery, not graph modeling. Keep the existing GenericAll-only parser and per-holder yield untouched. Only the `obj_type == "group"` branch changes: today it merely logs+yields; make it recurse membership. Scope strictly to **GenericAll** holders (ope-e191's stated scope). Preserve emit ordering.

**REQUIRED — huge-group range truncation must WARN (red flag for the operator):** AD returns the `member` attribute with range retrieval (`member;range=0-1499`) for groups larger than ~1500 members. If the shared `paged_search` does not transparently follow the ranges, membership silently truncates — which means SMC-controlling principals go undiscovered. This is unacceptable as a silent cap. The collector MUST detect a range-limited response (any returned attribute key of the form `member;range=`, or a `member` list at the server page cap with a `member;range=` sibling) and emit `logger.warning("SMC group expansion: group %s member list is range-limited (>%d members); membership truncated — some controlling principals may be undiscovered. Review manually.", group_dn, count)`. Do not silently proceed. Full range-following retrieval is out of scope for this task (note as a follow-up), but the WARNING is mandatory.

- [ ] **Step 1: Write failing tests** in `tests/test_ldap_smc_recursion.py` with a fake `ctx` (mirror the fakes in existing `tests/test_ldap_*.py`):

```python
def test_generic_all_group_expands_members_recursively(fake_ctx_smc_group):
    # group G1 (GenericAll) -> {computerA, group G2}; G2 -> {computerB, userC}
    ctx = fake_ctx_smc_group()
    list(ldap_system_management_dacl(ctx))
    assert {t.identifier for t in ctx.registered} == {"computerA.dns", "computerB.dns"}

def test_circular_group_nesting_terminates(fake_ctx_smc_cyclic):
    # G1 -> G2 -> G1 ; must return, not hang
    list(ldap_system_management_dacl(fake_ctx_smc_cyclic()))

def test_direct_computer_holder_unchanged(fake_ctx_smc_computer):
    ctx = fake_ctx_smc_computer()
    list(ldap_system_management_dacl(ctx))
    assert [t.identifier for t in ctx.registered] == ["directComputer.dns"]

def test_range_limited_group_membership_warns(fake_ctx_smc_range_limited, caplog):
    # group whose member fetch returns a "member;range=0-1499" key -> must WARN, not silently cap
    import logging
    caplog.set_level(logging.WARNING)
    ctx = fake_ctx_smc_range_limited()
    list(ldap_system_management_dacl(ctx))
    assert any("range-limited" in r.getMessage() and "truncated" in r.getMessage()
               for r in caplog.records)
```

- [ ] **Step 2: Run, expect FAIL.**

- [ ] **Step 3: Implement.** Add `from ldap3 import BASE` at the top of `ldap.py` if absent. Add the helper (module-level, near `_parse_sd_generic_all`):

```python
def _expand_group_targets(ctx: SourceContext, group_obj: dict[str, Any], visited: set[str]) -> None:
    """Recursively register computer members of a group that holds GenericAll on the
    System Management container (ope-e191). Users are logged (modeled elsewhere via the
    caller's yield), nested groups recurse; visited guards circular nesting."""
    group_sid = group_obj.get("object_sid")
    group_dn = group_obj.get("distinguished_name")
    if not group_dn or (group_sid and group_sid in visited):
        logger.debug("SMC group expansion: skipping visited/empty group %s (%s)", group_sid, group_dn)
        return
    if group_sid:
        visited.add(group_sid)
    grp = next(ctx.ad.paged_search("(objectClass=*)", ["member"], base=group_dn, scope=BASE), None) or {}
    members = grp.get("member") or []
    if isinstance(members, str):
        members = [members]
    # REQUIRED: range-limited (huge) groups must WARN, never silently truncate.
    range_keys = [k for k in grp if str(k).lower().startswith("member;range=")]
    if range_keys:
        for k in range_keys:
            extra = grp.get(k) or []
            members += [extra] if isinstance(extra, str) else list(extra)
        logger.warning(
            "SMC group expansion: group %s member list is range-limited (>%d members); "
            "membership truncated — some controlling principals may be undiscovered. Review manually.",
            group_dn, len(members))
    if not members:
        logger.debug("SMC group expansion: group %s has no members", group_dn)
        return
    for member_dn in members:
        member = ctx.resolve_principal(member_dn)
        if not member:
            logger.warning("SMC group expansion: could not resolve member %s", member_dn)
            continue
        oc = member.get("object_class", [])
        oc = [oc] if isinstance(oc, str) else oc
        ocl = [c.lower() for c in oc]
        if "computer" in ocl:
            ctx.register_target(identifier=member.get("dns_host_name"),
                                source="LDAP-GenericAllSystemManagement", ad_object=member)
        elif "group" in ocl:
            _expand_group_targets(ctx, member, visited)
        elif "user" in ocl:
            logger.info("SMC group expansion: user member %s controls the container (modeled, not a scan target)",
                        member.get("sam_account_name"))
        else:
            logger.warning("SMC group expansion: member %s has unhandled objectClass %s", member_dn, ocl)
```
Then in the holder loop's `elif "group" in [c.lower() for c in obj_class]:` branch (currently just sets `obj_type = "group"`), call `_expand_group_targets(ctx, ad_obj, set())` before the shared `logger.info(...)`/`yield ad_obj`. The parser is GenericAll-only, so every holder here already has GenericAll — matching ope-e191's scope. Every branch logs per the Global Constraints definition.

- [ ] **Step 4: Run tests, expect PASS.**

- [ ] **Step 5: Docs.** ARCHITECTURE.md §11 (recursive target discovery): note that GenericAll group holders on the SMC now expand recursively for target seeding; add a changelog entry.

- [ ] **Step 6: Green checkpoint (no commit).** `.venv/Scripts/python -m pytest ../tests/test_ldap_smc_recursion.py ../tests/test_allowed_targets.py -q`.

---

### Task 3: Clear all lint + close ope-1f0f

**Files:**
- Modify: `src/openhound_sccm/collectors/ldap.py:634`,`:635`,`:642`,`:660` (delete 4 unused locals)
- Modify: `src/openhound_sccm/main.py:611` (unused `ProxyConfig` import)

**Interfaces:** none (pure cleanup).

- [ ] **Step 1: Confirm current lint state:** from `sccm/sccm/`, `uv run ruff check src/openhound_sccm/` — expect exactly 5 errors: F841 `revision`/`control`/`acl_size`/`ace_flags` in `ldap.py` and F401 `ProxyConfig` in `main.py:611`.

- [ ] **Step 2: Delete the 4 unused SD-parser locals** in `_parse_sd_generic_all`. Only `offset_dacl` (`:636`) and `ace_count` (`:643`) are needed from the headers; `ace_type` (`:659`), `ace_size` (`:661`), and `access_mask` are used in the loop. Remove:
  - `:634` `revision = sd_bytes[0]`
  - `:635` `control = struct.unpack_from("<H", sd_bytes, 2)[0]`
  - `:642` `acl_size = struct.unpack_from("<H", sd_bytes, offset_dacl + 2)[0]`
  - `:660` `ace_flags = sd_bytes[pos + 1]`
  Keep the docstring's structure comments (they document the layout even though we skip those fields). GenericAll detection uses `access_mask` only, so behavior is unchanged.

- [ ] **Step 3: Fix the F401** — remove `ProxyConfig` from `from openhound_collector_common.proxy import ProxyConfig, SocksError, parse_proxy_address` at `main.py:611` (keep `SocksError`, `parse_proxy_address`). The function's return annotation uses the quoted forward-ref `"ProxyConfig"`, so the runtime import is not required; if a type checker complains, add the import under `if TYPE_CHECKING:`.

- [ ] **Step 4: Confirm tree-wide clean:** `uv run ruff check src/openhound_sccm/` → **"All checks passed!"** — satisfies `ope-1f0f` acceptance criterion #4.

- [ ] **Step 5: Verify the other `ope-1f0f` criteria still hold** (audit already confirmed: 0 bare `except:`, annotated `except Exception`, branch logging present, `Ope-f3di`/`Ope-scp1` closed & referenced). If `ruff` or a quick read surfaces anything else on touched files, fix it here.

- [ ] **Step 6: Green checkpoint (no commit).** Run the SMC-adjacent regression once more: `.venv/Scripts/python -m pytest ../tests/test_ldap_smc_recursion.py -q` and report `ruff` clean. `ope-b1e8`, `ope-e191`, `ope-1f0f` are now implemented; Meatbag commits and closes them.

---

## Deferred scope (Ope-liu7 — for the future ticket, NOT this plan)
When picking up `Ope-liu7` later, the remaining work is: (1) generalize `_parse_sd_generic_all` → `_parse_sd_control_aces` returning per-ACE `{sid, access_mask, ace_type, inherited, rights}` for GenericAll/GenericWrite/WriteDACL/WriteOwner/CreateChild (this is also where `ace_flags` would become *used* rather than deleted — note Task 3 deletes it, so it would be re-added); (2) emit per-ACE rows from the collector for edge modeling; (3) add `SCCM_ControlSystemManagement` to `kinds/edges.py` + `TRAVERSABLE_EDGE_KINDS`; (4) author its `edge_help.py` block (keep `PENDING_HELP_KINDS` empty); (5) add `_edge_control_system_management` in `transforms.py` (principal → each non-secondary site) with `smc_ace_rights`/`smc_ace_has_explicit` columns via the Stage-6 `coercion_*` precedent, mapped to CMBP-cased props in `models/graph_edge.py`; (6) README/ARCHITECTURE + tests.

## Self-Review
**Spec coverage:** ope-b1e8 → Task 1. ope-e191 (recurse group holders, computers→targets, users→modeled, visited-set) → Task 2. ope-1f0f (linter clean; other 4 criteria pre-verified) → Task 3. Ope-liu7 → intentionally deferred (documented above). ✅

**Placeholder scan:** all previously-flagged unknowns are now resolved against live code — Task 1 uses `inspect.signature(sccm_main.collect_sccm)` (no `CliRunner`; the command is a plain function); Task 2 uses `ctx.resolve_principal(member_dn)` (DN-aware, `context.py:184`) + a BASE-scope `member` fetch (`context.py:227-236` pattern); Task 3 line numbers verified (`revision`:634, `control`:635, `acl_size`:642, `ace_flags`:660). The one residual is defensive: re-confirm those four line numbers at edit time since Task 2 edits the same file first (functions differ, so no overlap expected).

**Type/name consistency:** `_expand_group_targets(ctx, group_obj, visited)` signature is self-contained in Task 2; no cross-task interfaces remain now that the edge tasks are gone.

**Decision log:** remove `--sms` (not wire/deprecate); e191 recursion scoped to GenericAll holders for target discovery only; F841s deleted (not repurposed) because the edge work that would use `ace_flags` is deferred; `Ope-liu7` stays open.

## Execution Handoff
Plan saved to `sccm/sccm/docs/superpowers/plans/2026-07-21-tier1-tier2-smc-abuse-and-cleanup.md`. Two execution options:
1. **Subagent-Driven (recommended)** — fresh subagent per task, two-stage review between tasks; uses superpowers:subagent-driven-development; fits the in-repo `.sdd/` no-commit harness.
2. **Inline Execution** — run tasks in this session with checkpoints; uses superpowers:executing-plans.

Which approach?
